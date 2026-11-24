"""Author exact original MCP input-contract diagnostics as native HIA.

The frozen catalog is compiled into immutable HIA word stores. Runtime schema
decisions, error priority, path construction and JSON rendering execute in HIA.
The input is the parent's compact, key-sorted serde-compatible Value encoding.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_schema import CATALOG, HELPERS, PAYLOAD_HELPERS, table
from tools.generate_hia_worker_request import data_source, decimal_program
from tools.generate_hia_mcp_service import document

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/mcp_input_diagnostic.hepta'
AUXILIARY_BYTES = (8 << 20) + 131072
OUTPUT_BYTES = (8 << 20) + 512
WORKSPACE_BYTES = 32 << 20
NONE = (1 << 64) - 1
PATTERNS = {
    '^(0|[1-9][0-9]{0,19})$': 1,
    '^[0-9a-f]{64}$': 2,
    '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$': 3,
    '^hia://artifacts/[A-Za-z0-9][A-Za-z0-9._~-]{0,191}$': 4,
}
ERRORS = (
    ': value is forbidden',
    ': unexpected JSON type',
    ': value differs from the required constant',
    ': unsupported value',
    ': oneOf constraints are not satisfied',
    ': anyOf constraints are not satisfied',
    ': allOf constraints are not satisfied',
    ': forbidden field combination',
    ': required field is absent',
    ': array length is outside its bound',
    ': repeated array item',
    ': required array member is absent',
    ': string length is outside its bound',
    ': string does not match its declared pattern',
    ': unsigned decimal exceeds u64',
    ': number is outside its bound',
    'HIA schema validation depth exceeded',
    'HIA arguments exceed the admitted serialized bound',
    'unregistered HIA tool',
)
KEYWORDS = frozenset(('$schema','description','type','const','enum','required',
    'minimum','maximum','minLength','maxLength','minItems','maxItems','uniqueItems',
    'pattern','properties','additionalProperties','items','contains','not',
    'if','then','oneOf','anyOf','allOf'))


def normalized(schema):
    if type(schema) is bool:
        return schema
    if type(schema) is not dict or set(schema) - KEYWORDS:
        raise ValueError(('unsupported original schema vocabulary',schema))
    result={}
    for key,value in schema.items():
        if key in ('$schema','description'):
            continue
        if key=='properties':
            value={name:normalized(sub) for name,sub in sorted(value.items())}
        elif key in ('additionalProperties','items','contains','not','if','then'):
            value=normalized(value)
        elif key in ('oneOf','anyOf','allOf'):
            value=[normalized(sub) for sub in value]
        result[key]=value
    return result


class Tables:
    def __init__(self, raw):
        self.rules=[]; self.ids={}
        self.add(False);self.add(True)
        self.roots=[self.add(tool['inputSchema']) for tool in json.loads(raw)['tools']]
        if len(self.roots)!=11:
            raise ValueError('the original input diagnostic catalog requires eleven tools')
        self.data=bytearray(512+128*len(self.rules))
        self.strings={};self.vectors={}
        for index,root in enumerate(self.roots):
            self.word(index*8,root)
        for index,message in enumerate(ERRORS):
            pointer,length=self.string(message)
            self.word(128+index*16,pointer);self.word(136+index*16,length)
        prefix='{"code":-32602,"message":"HIA input does not match its advertised contract: '
        pointer,length=self.string(prefix)
        self.word(448,pointer);self.word(456,length)
        pointer,length=self.string('arguments')
        self.word(464,pointer);self.word(472,length)
        for index,schema in enumerate(self.rules):
            self.rule(index,schema)
        self.data.extend(bytes((-len(self.data))%8))
        if len(self.data)>65000:
            raise ValueError('compiled diagnostic schema table exceeds its fixed region')

    def key(self,value):
        return json.dumps(value,sort_keys=True,separators=(',',':'))

    def add(self,schema):
        schema=normalized(schema);key=self.key(schema)
        if key in self.ids:return self.ids[key]
        result=len(self.rules);self.ids[key]=result;self.rules.append(schema)
        if type(schema) is dict:
            for name,value in schema.items():
                if name=='properties':
                    for sub in value.values():self.add(sub)
                elif name in ('additionalProperties','items','contains','not','if','then'):
                    self.add(value)
                elif name in ('oneOf','anyOf','allOf'):
                    for sub in value:self.add(sub)
        return result

    def word(self,at,value):
        struct.pack_into('<Q',self.data,at,value)

    def vector(self,values):
        key=tuple(values)
        if key not in self.vectors:
            self.data.extend(bytes((-len(self.data))%8))
            self.vectors[key]=len(self.data)
            self.data.extend(struct.pack('<'+'Q'*len(key),*key))
        return self.vectors[key]

    def string(self,value):
        raw=value.encode('utf-8')
        if raw not in self.strings:
            self.strings[raw]=len(self.data)
            self.data.extend(raw)
        return self.strings[raw],len(raw)

    def rule(self,index,schema):
        base=512+index*128
        def field(at,value):struct.pack_into('<I',self.data,base+at//2,value)
        if type(schema) is bool:
            field(232,2 if schema else 1);return
        kinds={None:0,'object':1,'array':2,'string':3,'boolean':4,'null':5,
               'integer':6,'number':7}
        field(0,kinds[schema.get('type')])
        if 'const' in schema:
            if type(schema['const']) is not str:raise ValueError('non-text constant outside frozen inputs')
            p,n=self.string(schema['const']);field(8,p);field(16,n)
        if 'enum' in schema:
            values=[]
            for value in schema['enum']:
                if type(value) is not str:raise ValueError('non-text enum outside frozen inputs')
                values.extend(self.string(value))
            field(24,self.vector(values));field(32,len(values)//2)
        for name,at in [('oneOf',40),('anyOf',56),('allOf',72)]:
            if name in schema:
                values=[self.ids[self.key(sub)] for sub in schema[name]]
                field(at,self.vector(values));field(at+8,len(values))
        for name,at in [('not',88),('if',96),('then',104),
                        ('additionalProperties',144),('items',168),('contains',176)]:
            if name in schema:field(at,self.ids[self.key(schema[name])]+1)
        if 'required' in schema:
            values=[]
            for value in schema['required']:values.extend(self.string(value))
            field(112,self.vector(values));field(120,len(values)//2)
        if 'properties' in schema:
            values=[]
            for name,sub in schema['properties'].items():
                values.extend((*self.string(name),self.ids[self.key(sub)]))
            field(128,self.vector(values));field(136,len(values)//3)
        for name,at in [('minItems',152),('maxItems',160),('minLength',192),
                        ('maxLength',200),('minimum',216),('maximum',224)]:
            if name in schema:
                value=schema[name]
                if type(value) is not int or not 0<=value<=1<<30:
                    raise ValueError(('unsupported frozen numeric bound',name,value))
                field(at,value+1)
        if schema.get('uniqueItems') is True:field(184,1)
        if 'pattern' in schema:field(208,PATTERNS[schema['pattern']])

    def source(self):
        stores=[(at,int.from_bytes(self.data[at:at+8],'little'))
                for at in range(0,len(self.data),8) if any(self.data[at:at+8])]
        code='\ndef initialize(w:mutbuf) -> u64:\n    base = database(w)\n    index = 0\n    while index < 65536:\n        word_store(w, base + index, 0)\n        index = index + 8\n'
        helpers=''
        for bank,start in enumerate(range(0,len(stores),64)):
            code+=f'    table_{bank}(w, base)\n'
            helpers+=f'\ndef table_{bank}(w:mutbuf, base:u64) -> u64:\n'
            rows=stores[start:start+64]
            # Reuse literal values and strides in each bounded bank. These are
            # ordinary HIA locals, keeping constant-table emission within the
            # existing 8192-operation compiler budget.
            values=[]
            for position,(at,value) in enumerate(rows):
                values.append(value)
                if position:values.append(at-rows[position-1][0])
            counts={value:values.count(value) for value in set(values)}
            common={value:'c'+str(index) for index,value in enumerate(sorted(
                value for value,count in counts.items() if count>1))}
            for value,name in common.items():helpers+=f'    {name} = {value}\n'
            helpers+=f'    cursor = base + {rows[0][0]}\n'
            for position,(at,value) in enumerate(rows):
                if position:
                    delta=at-rows[position-1][0]
                    helpers+=f'    cursor = cursor + {common.get(delta,str(delta))}\n'
                helpers+=f'    word_store(w, cursor, {common.get(value,str(value))})\n'
            helpers+='    return 0\n'
        return code+'    return 0\n'+helpers


POLICY = r'''
def diagnose(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(w) < 33554432 or length(o) < 8389120:
        return 4294967293
    role = get(w, 0)
    if pinned_catalog(w, 8, 64) == 0 or role < 1 or role > 11:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    size = widen(decode_json(s, w, o))
    if size >= 4294967292:
        return size
    if size > database(w):
        return 4294967293
    initialize(w)
    root = get(w, database(w) + (role - 1) * 8)
    base = database(w)
    copy_memory(w, base + get(w, base + 464), path(w), get(w, base + 472))
    if check(s, w, root, 64, 9, 0) != 0:
        if length(s) <= 524288:
            return 0
        refuse(w, 18, 0)
    return render_error(w, o)

def schema_word(w:mutbuf, at:u64) -> u64:
    return word_load(w, at) & 4294967295

def database(w:mutbuf) -> u64:
    return length(w) - 8519680

def path(w:mutbuf) -> u64:
    return database(w) + 65536

def misc(w:mutbuf) -> u64:
    return length(w) - 65536

def refuse(w:mutbuf, code:u64, plen:u64) -> u64:
    word_store(w, misc(w), code)
    word_store(w, misc(w) + 8, plen)
    return 0

def copy_memory(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    index = 0
    while index + 8 <= size:
        word_store(w, target + index, get(w, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return target + size

def equal_memory(w:mutbuf, left:u64, right:u64, size:u64) -> bool:
    index = 0
    while index + 8 <= size:
        if get(w, left + index) != get(w, right + index):
            return False
        index = index + 8
    while index < size:
        if byte(w, left + index) != byte(w, right + index):
            return False
        index = index + 1
    return True

def equal_source(s:readbuf, left:u64, right:u64, size:u64) -> bool:
    index = 0
    while index < size:
        if byte(s, left + index) != byte(s, right + index):
            return False
        index = index + 1
    return True

def member(w:mutbuf, node:u64, key:u64, size:u64) -> u64:
    item = get(w, node + 24)
    while item != 18446744073709551615:
        child = 64 + item * 56
        if get(w, child + 48) == size and equal_memory(w, get(w, child + 40), key, size):
            return child
        item = get(w, child + 16)
    return 18446744073709551615

def member_path(w:mutbuf, plen:u64, start:u64, size:u64) -> u64:
    store(w, path(w) + plen, 46)
    copy_memory(w, start, path(w) + plen + 1, size)
    return plen + 1 + size

def index_path(w:mutbuf, plen:u64, value:u64) -> u64:
    target = path(w) + plen
    store(w, target, 91)
    count = 0
    while count == 0 or value != 0:
        store(w, misc(w) + 32 + count, 48 + value % 10)
        value = value // 10
        count = count + 1
    index = 0
    while index < count:
        store(w, target + 1 + index, byte(w, misc(w) + 31 + count - index))
        index = index + 1
    store(w, target + 1 + count, 93)
    return plen + count + 2

def matches(s:readbuf, w:mutbuf, node:u64, kind:u64) -> bool:
    actual = get(w, node)
    if kind == 0:
        return True
    if kind == 1:
        return actual == 6
    if kind == 2:
        return actual == 5
    if kind == 3:
        return actual == 4
    if kind == 4:
        return actual == 1 or actual == 2
    if kind == 5:
        return actual == 0
    if kind == 6:
        return unrestricted_integer(s, w, node) != 0
    return actual == 3 or actual == 7

def literal(w:mutbuf, node:u64, start:u64, size:u64) -> bool:
    return get(w, node) == 4 and get(w, node + 32) == size and equal_memory(w, get(w, node + 24), start, size)

def check(s:readbuf, w:mutbuf, rule:u64, node:u64, plen:u64, depth:u64) -> u64:
    if depth > 64:
        return refuse(w, 17, 0)
    schema = database(w) + 512 + rule * 128
    boolean = schema_word(w, schema + 116)
    if boolean == 1:
        return refuse(w, 1, plen)
    if boolean == 2:
        return 1
    if matches(s, w, node, schema_word(w, schema)) == False:
        return refuse(w, 2, plen)
    if schema_word(w, schema + 4) != 0:
        if literal(w, node, database(w) + schema_word(w, schema + 4), schema_word(w, schema + 8)) == False:
            return refuse(w, 3, plen)
    count = schema_word(w, schema + 16)
    if count != 0:
        values = database(w) + schema_word(w, schema + 12)
        index = 0
        found = False
        while index < count:
            row = values + index * 16
            if literal(w, node, database(w) + get(w, row), get(w, row + 8)):
                found = True
            index = index + 1
        if found == False:
            return refuse(w, 4, plen)
    index = 0
    while index < 3:
        offset = 20 + index * 8
        count = schema_word(w, schema + offset + 4)
        if count != 0:
            values = database(w) + schema_word(w, schema + offset)
            choice = 0
            matched = 0
            while choice < count:
                matched = matched + check(s, w, get(w, values + choice * 8), node, plen, depth + 1)
                choice = choice + 1
            if (index == 0 and matched != 1) or (index == 1 and matched == 0) or (index == 2 and matched != count):
                return refuse(w, 5 + index, plen)
        index = index + 1
    forbidden = schema_word(w, schema + 44)
    if forbidden != 0 and check(s, w, forbidden - 1, node, plen, depth + 1) != 0:
        return refuse(w, 8, plen)
    condition = schema_word(w, schema + 48)
    if condition != 0 and check(s, w, condition - 1, node, plen, depth + 1) != 0:
        consequence = schema_word(w, schema + 52)
        if consequence != 0 and check(s, w, consequence - 1, node, plen, depth + 1) == 0:
            return 0
    kind = get(w, node)
    if kind == 6 and check_object(s, w, schema, node, plen, depth) == 0:
        return 0
    if kind == 5 and check_array(s, w, schema, node, plen, depth) == 0:
        return 0
    if kind == 4 and check_string(w, schema, node, plen) == 0:
        return 0
    low = schema_word(w, schema + 108)
    high = schema_word(w, schema + 112)
    if (kind == 3 or kind == 7) and (low != 0 or high != 0):
        if low == 0 or high == 0:
            return refuse(w, 16, plen)
        if integer_between(s, w, node, low - 1, high - 1) == 0:
            return refuse(w, 16, plen)
    return 1

def check_object(s:readbuf, w:mutbuf, schema:u64, node:u64, plen:u64, depth:u64) -> u64:
    values = database(w) + schema_word(w, schema + 56)
    count = schema_word(w, schema + 60)
    index = 0
    while index < count:
        row = values + index * 16
        key = database(w) + get(w, row)
        size = get(w, row + 8)
        if member(w, node, key, size) == 18446744073709551615:
            return refuse(w, 9, member_path(w, plen, key, size))
        index = index + 1
    values = database(w) + schema_word(w, schema + 64)
    count = schema_word(w, schema + 68)
    item = get(w, node + 24)
    while item != 18446744073709551615:
        child = 64 + item * 56
        key = get(w, child + 40)
        size = get(w, child + 48)
        selected = schema_word(w, schema + 72)
        index = 0
        while index < count:
            row = values + index * 24
            if get(w, row + 8) == size and equal_memory(w, database(w) + get(w, row), key, size):
                selected = get(w, row + 16) + 1
            index = index + 1
        if selected != 0:
            next = member_path(w, plen, key, size)
            if check(s, w, selected - 1, child, next, depth + 1) == 0:
                return 0
        item = get(w, child + 16)
    return 1

def check_array(s:readbuf, w:mutbuf, schema:u64, node:u64, plen:u64, depth:u64) -> u64:
    count = get(w, node + 32)
    low = schema_word(w, schema + 76)
    high = schema_word(w, schema + 80)
    if (low != 0 and count < low - 1) or (high != 0 and count > high - 1):
        return refuse(w, 10, plen)
    if schema_word(w, schema + 92) != 0:
        item = get(w, node + 24)
        while item != 18446744073709551615:
            other = get(w, node + 24)
            while other != item:
                if values_equal(s, w, 64 + item * 56, 64 + other * 56):
                    return refuse(w, 11, plen)
                other = get(w, 64 + other * 56 + 16)
            item = get(w, 64 + item * 56 + 16)
    rule = schema_word(w, schema + 84)
    if rule != 0:
        item = get(w, node + 24)
        index = 0
        while item != 18446744073709551615:
            child = 64 + item * 56
            next = index_path(w, plen, index)
            if check(s, w, rule - 1, child, next, depth + 1) == 0:
                return 0
            item = get(w, child + 16)
            index = index + 1
    rule = schema_word(w, schema + 88)
    if rule != 0:
        found = False
        item = get(w, node + 24)
        while item != 18446744073709551615 and found == False:
            child = 64 + item * 56
            found = check(s, w, rule - 1, child, plen, depth + 1) != 0
            item = get(w, child + 16)
        if found == False:
            return refuse(w, 12, plen)
    return 1

def values_equal(s:readbuf, w:mutbuf, left:u64, right:u64) -> bool:
    kind = get(w, left)
    if kind != get(w, right):
        return False
    if kind <= 2:
        return True
    size = get(w, left + 32)
    if kind == 7:
        if widen(decimal_convert(s, w, get(w, left + 24), size)) != 8:
            return False
        a = get(w, length(w) - 192)
        if widen(decimal_convert(s, w, get(w, right + 24), get(w, right + 32))) != 8:
            return False
        b = get(w, length(w) - 192)
        return a == b or ((a & 9223372036854775807) == 0 and (b & 9223372036854775807) == 0)
    if size != get(w, right + 32):
        return False
    if kind == 3:
        return equal_source(s, get(w, left + 24), get(w, right + 24), size)
    if kind == 4:
        return equal_memory(w, get(w, left + 24), get(w, right + 24), size)
    a = get(w, left + 24)
    b = get(w, right + 24)
    while a != 18446744073709551615:
        la = 64 + a * 56
        rb = 64 + b * 56
        if kind == 6:
            if get(w, la + 48) != get(w, rb + 48) or equal_memory(w, get(w, la + 40), get(w, rb + 40), get(w, la + 48)) == False:
                return False
        if values_equal(s, w, la, rb) == False:
            return False
        a = get(w, la + 16)
        b = get(w, rb + 16)
    return True

def check_string(w:mutbuf, schema:u64, node:u64, plen:u64) -> u64:
    start = get(w, node + 24)
    size = get(w, node + 32)
    low = schema_word(w, schema + 96)
    high = schema_word(w, schema + 100)
    if low != 0 or high != 0:
        count = string_length(w, start, size)
        if (low != 0 and count < low - 1) or (high != 0 and count > high - 1):
            return refuse(w, 13, plen)
    role = schema_word(w, schema + 104)
    if role != 0:
        if pattern(w, start, size, role) == 0:
            return refuse(w, 14, plen)
        if role == 1 and decimal_u64(w, start, size) == False:
            return refuse(w, 15, plen)
    return 1

def decimal_u64(w:mutbuf, start:u64, size:u64) -> bool:
    value = 0
    index = 0
    while index < size:
        digit = byte(w, start + index) - 48
        if digit > 9 or value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return False
        value = value * 10 + digit
        index = index + 1
    return True

def output_copy(w:mutbuf, o:mutbuf, start:u64, size:u64, at:u64) -> u64:
    index = 0
    while index + 8 <= size:
        word_store(o, at + index, get(w, start + index))
        index = index + 8
    while index < size:
        store(o, at + index, byte(w, start + index))
        index = index + 1
    return at + size

def quote_path(w:mutbuf, o:mutbuf, start:u64, size:u64, at:u64) -> u64:
    index = 0
    while index < size:
        if at + 6 > length(o):
            return 4294967293
        unit = byte(w, start + index)
        if unit == 34 or unit == 92:
            store(o, at, 92)
            store(o, at + 1, unit)
            at = at + 2
        elif unit == 8 or unit == 9 or unit == 10 or unit == 12 or unit == 13:
            code = choose(unit == 8, 98, choose(unit == 9, 116, choose(unit == 10, 110, choose(unit == 12, 102, 114))))
            store(o, at, 92)
            store(o, at + 1, code)
            at = at + 2
        elif unit < 32:
            store(o, at, 92)
            store(o, at + 1, 117)
            store(o, at + 2, 48)
            store(o, at + 3, 48)
            store(o, at + 4, 48 + (unit >> 4))
            digit = unit & 15
            store(o, at + 5, choose(digit < 10, 48 + digit, 87 + digit))
            at = at + 6
        else:
            store(o, at, unit)
            at = at + 1
        index = index + 1
    return at

def render_error(w:mutbuf, o:mutbuf) -> u32:
    base = database(w)
    code = get(w, misc(w))
    plen = get(w, misc(w) + 8)
    if code < 1 or code > 19 or plen > 8388736:
        return 4294967293
    at = output_copy(w, o, base + get(w, base + 448), get(w, base + 456), 0)
    at = quote_path(w, o, path(w), plen, at)
    if at >= 4294967292:
        return at
    row = base + 128 + (code - 1) * 16
    size = get(w, row + 8)
    if at + size + 2 > length(o):
        return 4294967293
    at = output_copy(w, o, base + get(w, row), size, at)
    store(o, at, 34)
    store(o, at + 1, 125)
    return at + 2
'''


def source_program(raw=None):
    raw=CATALOG.read_bytes() if raw is None else raw
    tables=Tables(raw)
    helpers=HELPERS.replace('URI_HEAD',str(int.from_bytes(b'hia://ar','little')))
    helpers=helpers.replace('URI_TAIL',str(int.from_bytes(b'tifacts/','little')))
    # Rust regex's default dollar anchor is the actual end of the string.
    old='    # The hosted regex\'s final dollar sign also matches before a final LF.\n    if size > 0 and byte(w, start + size - 1) == 10:\n        size = size - 1\n'
    if old not in helpers:raise ValueError('reviewed pattern helper changed')
    helpers=helpers.replace(old,'',1)
    integer=PAYLOAD_HELPERS[PAYLOAD_HELPERS.index('\ndef unrestricted_integer('):PAYLOAD_HELPERS.index('\ndef unit_number(')]
    return '\n'.join((POLICY,tables.source(),
        table('pinned_catalog',[(1,sha256(raw).hexdigest())]),helpers,integer,
        data_source(),decimal_program()))


def main():
    source=source_program()
    module=document(source,'mcp_input_diagnostic')
    SOURCE.write_text(render_assembly(module))
    print(json.dumps({'source':str(SOURCE),'bytes':SOURCE.stat().st_size,
        'functions':len(module['functions']),
        'blocks':sum(len(f['blocks']) for f in module['functions']),
        'ops':sum(len(b['ops']) for f in module['functions'] for b in f['blocks']),
        'schema_rules':len(Tables(CATALOG.read_bytes()).rules),
        'table_bytes':len(Tables(CATALOG.read_bytes()).data)},sort_keys=True))

if __name__=='__main__':main()
