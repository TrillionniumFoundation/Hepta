"""Author the HIA decoder of the original closed system jobctl Request.

This component consumes the strict UTF-8 JSON arena produced by the companion
HIA decoder. It implements Rust Request field types/defaults, duplicate-field
refusal, last-wins BTreeMap environment ordering and exact struct serialization.
It performs no privileged effects.
"""
from __future__ import annotations
import argparse,re,ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_json_decode import source_program as base_json_source

ROOT=Path(__file__).resolve().parents[1]
STATE_BYTES=128<<20
ARENA=4<<20
ARENA_BYTES=64<<20
RAW=1<<20
SCRATCH=68<<20
SCRATCH_BYTES=32<<20
REQUEST_OUT=112<<20
REQUEST_CAP=2<<20
ENV_INDEX=108<<20
ENV_TEMP=110<<20
TABLE=512
VALUES=768
ENV_COUNT=920
REQUEST_SIZE=928
OVERRIDE_CWD=944
OVERRIDE_CWD_SIZE=952
OVERRIDE_TIMEOUT=960
OVERRIDE_MASK=968
ERROR=976
FIELDS=('op','job_id','executable','args','cwd','env','stdin','timeout_seconds','nice','cpu_quota_percent','memory_max_bytes','stdout_offset','stderr_offset','limit')

POLICY=r"""
def request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 1048576 or length(w) != STATE_BYTES or length(o) != 128:
        return 0
    if get(w, ARENA) != ARENA_MAGIC or get(w, ARENA + 40) != length(s):
        return 0
    if get(w, ARENA + 8) == 0 or get(w, ARENA + 8) > 1048576:
        return 0
    kind = node(w, 0, 0)
    if get(w, ARENA + 24) > ARENA_BYTES or (kind != 6 and kind != 5):
        return 0
    put(w, ERROR, 0)
    index = 0
    while index < 14:
        put(w, TABLE + index * 8, NONE)
        put(w, VALUES + index * 8, 0)
        index = index + 1
    child = node(w, 0, 24)
    mask = 0
    ordinal = 0
    while child != NONE:
        ordinal = ordinal + 1
        if kind == 5:
            if ordinal > 14:
                return 0
            field = ordinal
        else:
            field = key_id(w, ARENA + node(w, child, 40), node(w, child, 48))
        if field == 0 or mask & (1 << (field - 1)) != 0:
            return 0
        mask = mask | (1 << (field - 1))
        put(w, TABLE + (field - 1) * 8, child)
        child = node(w, child, 16)
    if mask & 3 != 3:
        return 0
    index = 0
    while index < 14:
        child = get(w, TABLE + index * 8)
        if child != NONE:
            kind = node(w, child, 0)
            if index == 0 or index == 1 or index == 2:
                if kind != 4:
                    return 0
            elif index == 4 or index == 6:
                if kind != 4 and kind != 0:
                    return 0
            elif index == 3:
                if kind != 5 or strings_only(w, child) == 0:
                    return 0
            elif index == 5:
                if kind != 6 or strings_only(w, child) == 0:
                    return 0
            else:
                if kind == 0 and index != 11 and index != 12:
                    put(w, VALUES + index * 8, 0)
                elif kind == 3:
                    value = integer(s, w, child)
                    if get(w, ERROR) != 0:
                        return 0
                    if index == 8 and value > 255:
                        return 0
                    if index == 9 and value > 65535:
                        return 0
                    put(w, VALUES + index * 8, value)
                else:
                    return 0
        index = index + 1
    if environment(w) == 0:
        return 0
    if get(w, OVERRIDE_MASK) & 4 != 0 and validate_start(w) == 0:
        return 0
    at = REQUEST_OUT
    store(w, at, 123)
    at = at + 1
    index = 0
    while index < 14:
        if index != 0:
            store(w, at, 44)
            at = at + 1
        at = field_text(w, index, at)
        at = emit_value(s, w, at, index)
        if at == NONE or at > REQUEST_OUT + REQUEST_CAP - 2:
            return 0
        index = index + 1
    store(w, at, 125)
    put(w, REQUEST_SIZE, at + 1 - REQUEST_OUT)
    return 1

def validate_start(w:mutbuf) -> u64:
    child = get(w, TABLE + 16)
    if child == NONE or node(w, child, 32) == 0:
        return 0
    start = ARENA + node(w, child, 24)
    if byte(w, start) != 47 or clean_string(w, child, 1048576) == 0:
        return 0
    child = get(w, TABLE + 24)
    if child != NONE:
        if node(w, child, 32) > 256:
            return 0
        child = node(w, child, 24)
        while child != NONE:
            if clean_string(w, child, 65536) == 0:
                return 0
            child = node(w, child, 16)
    if get(w, ENV_COUNT) > 64:
        return 0
    index = 0
    while index < get(w, ENV_COUNT):
        child = get(w, ENV_INDEX + index * 8)
        start = ARENA + node(w, child, 40)
        size = node(w, child, 48)
        if size == 0 or (byte(w, start) >= 48 and byte(w, start) <= 57):
            return 0
        offset = 0
        while offset < size:
            point = byte(w, start + offset)
            if (point < 48 or point > 57) and (point < 65 or point > 90) and (point < 97 or point > 122) and point != 95:
                return 0
            offset = offset + 1
        if reserved_environment(w, start, size) == 1 or clean_string(w, child, 65536) == 0:
            return 0
        index = index + 1
    timeout = get(w, 2072)
    if present(w, 7) == 1:
        timeout = get(w, VALUES + 56)
    if timeout == 0 or timeout > get(w, 2072):
        return 0
    if present(w, 9) == 1 and (get(w, VALUES + 72) == 0 or get(w, VALUES + 72) > get(w, 2080)):
        return 0
    if present(w, 10) == 1 and (get(w, VALUES + 80) < 67108864 or get(w, VALUES + 80) > get(w, 2088)):
        return 0
    if present(w, 8) == 1 and get(w, VALUES + 64) > 19:
        return 0
    put(w, OVERRIDE_TIMEOUT, timeout)
    put(w, OVERRIDE_MASK, get(w, OVERRIDE_MASK) | 2)
    return 1

def present(w:mutbuf, index:u64) -> u64:
    child = get(w, TABLE + index * 8)
    if child == NONE or node(w, child, 0) == 0:
        return 0
    return 1

def clean_string(w:mutbuf, child:u64, maximum:u64) -> u64:
    size = node(w, child, 32)
    if size > maximum:
        return 0
    at = ARENA + node(w, child, 24)
    index = 0
    while index < size:
        if byte(w, at + index) == 0:
            return 0
        index = index + 1
    return 1

def strings_only(w:mutbuf, container:u64) -> u64:
    child = node(w, container, 24)
    while child != NONE:
        if node(w, child, 0) != 4:
            return 0
        child = node(w, child, 16)
    return 1

def integer(s:readbuf, w:mutbuf, child:u64) -> u64:
    start = node(w, child, 24)
    size = node(w, child, 32)
    if size == 0 or size > 20 or start + size > length(s):
        put(w, ERROR, 1)
        return 0
    value = 0
    index = 0
    while index < size:
        point = byte(s, start + index)
        if point < 48 or point > 57:
            put(w, ERROR, 1)
            return 0
        digit = point - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            put(w, ERROR, 1)
            return 0
        value = value * 10 + digit
        index = index + 1
    return value

def environment(w:mutbuf) -> u64:
    child = get(w, TABLE + 40)
    count = 0
    if child != NONE:
        child = node(w, child, 24)
        while child != NONE:
            if count >= 262144:
                return 0
            put(w, ENV_INDEX + count * 8, child)
            count = count + 1
            child = node(w, child, 16)
    width = 1
    while width < count:
        first = 0
        while first < count:
            middle = first + width
            if middle > count:
                middle = count
            stop = first + width * 2
            if stop > count:
                stop = count
            left = first
            right = middle
            target = first
            while target < stop:
                if right == stop:
                    selected = get(w, ENV_INDEX + left * 8)
                    left = left + 1
                elif left == middle:
                    selected = get(w, ENV_INDEX + right * 8)
                    right = right + 1
                elif compare_key(w, get(w, ENV_INDEX + left * 8), get(w, ENV_INDEX + right * 8)) != 2:
                    selected = get(w, ENV_INDEX + left * 8)
                    left = left + 1
                else:
                    selected = get(w, ENV_INDEX + right * 8)
                    right = right + 1
                put(w, ENV_TEMP + target * 8, selected)
                target = target + 1
            first = stop
        index = 0
        while index < count:
            put(w, ENV_INDEX + index * 8, get(w, ENV_TEMP + index * 8))
            index = index + 1
        width = width * 2
    index = 0
    target = 0
    while index < count:
        selected = get(w, ENV_INDEX + index * 8)
        index = index + 1
        while index < count and compare_key(w, selected, get(w, ENV_INDEX + index * 8)) == 1:
            selected = get(w, ENV_INDEX + index * 8)
            index = index + 1
        put(w, ENV_INDEX + target * 8, selected)
        target = target + 1
    put(w, ENV_COUNT, target)
    return 1

def compare_key(w:mutbuf, left:u64, right:u64) -> u64:
    left_at = ARENA + node(w, left, 40)
    right_at = ARENA + node(w, right, 40)
    left_size = node(w, left, 48)
    right_size = node(w, right, 48)
    index = 0
    while index < left_size and index < right_size:
        a = byte(w, left_at + index)
        b = byte(w, right_at + index)
        if a < b:
            return 0
        if a > b:
            return 2
        index = index + 1
    if left_size < right_size:
        return 0
    if left_size > right_size:
        return 2
    return 1

def emit_value(s:readbuf, w:mutbuf, at:u64, index:u64) -> u64:
    child = get(w, TABLE + index * 8)
    if index == 4 and get(w, OVERRIDE_MASK) & 1 != 0:
        return quote(w, at, get(w, OVERRIDE_CWD), get(w, OVERRIDE_CWD_SIZE))
    if index == 7 and get(w, OVERRIDE_MASK) & 2 != 0:
        return decimal(w, at, get(w, OVERRIDE_TIMEOUT))
    if index == 0 or index == 1 or index == 2 or index == 4 or index == 6:
        if child == NONE or node(w, child, 0) == 0:
            if index == 2:
                putn(w, at, 8738, 2)
                return at + 2
            return null(w, at)
        return quote(w, at, ARENA + node(w, child, 24), node(w, child, 32))
    if index == 3:
        store(w, at, 91)
        at = at + 1
        first = 1
        if child != NONE:
            child = node(w, child, 24)
            while child != NONE:
                if first == 0:
                    store(w, at, 44)
                    at = at + 1
                first = 0
                at = quote(w, at, ARENA + node(w, child, 24), node(w, child, 32))
                if at == NONE:
                    return NONE
                child = node(w, child, 16)
        store(w, at, 93)
        return at + 1
    if index == 5:
        store(w, at, 123)
        at = at + 1
        item = 0
        while item < get(w, ENV_COUNT):
            child = get(w, ENV_INDEX + item * 8)
            if item != 0:
                store(w, at, 44)
                at = at + 1
            at = quote(w, at, ARENA + node(w, child, 40), node(w, child, 48))
            if at == NONE:
                return NONE
            store(w, at, 58)
            at = quote(w, at + 1, ARENA + node(w, child, 24), node(w, child, 32))
            if at == NONE:
                return NONE
            item = item + 1
        store(w, at, 125)
        return at + 1
    if child == NONE or node(w, child, 0) == 0:
        if index == 11 or index == 12:
            store(w, at, 48)
            return at + 1
        return null(w, at)
    return decimal(w, at, get(w, VALUES + index * 8))

def quote(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    if source + size > length(w):
        return NONE
    store(w, at, 34)
    at = at + 1
    index = 0
    while index < size:
        if at > REQUEST_OUT + REQUEST_CAP - 8:
            return NONE
        point = byte(w, source + index)
        if point == 34 or point == 92:
            store(w, at, 92)
            store(w, at + 1, point)
            at = at + 2
        elif point == 8 or point == 9 or point == 10 or point == 12 or point == 13:
            short = 98
            if point == 9:
                short = 116
            elif point == 10:
                short = 110
            elif point == 12:
                short = 102
            elif point == 13:
                short = 114
            store(w, at, 92)
            store(w, at + 1, short)
            at = at + 2
        elif point < 32:
            putn(w, at, 808482140, 4)
            store(w, at + 4, hexadecimal(point >> 4))
            store(w, at + 5, hexadecimal(point & 15))
            at = at + 6
        else:
            store(w, at, point)
            at = at + 1
        index = index + 1
    store(w, at, 34)
    return at + 1

def decimal(w:mutbuf, at:u64, value:u64) -> u64:
    count = 0
    while value >= 10:
        store(w, 3000 + count, 48 + value % 10)
        value = value // 10
        count = count + 1
    store(w, at, value + 48)
    at = at + 1
    while count != 0:
        count = count - 1
        store(w, at, byte(w, 3000 + count))
        at = at + 1
    return at

def null(w:mutbuf, at:u64) -> u64:
    putn(w, at, 1819047278, 4)
    return at + 4

def hexadecimal(value:u64) -> u64:
    return choose(value < 10, 48 + value, 87 + value)

def node(w:mutbuf, index:u64, offset:u64) -> u64:
    return get(w, ARENA + 64 + index * 56 + offset)

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def getn(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 8:
        return word_load(w, at)
    value = 0
    index = 0
    while index < size:
        value = value | (byte(w, at + index) << (8 * index))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, at, value)
    return 0

def putn(w:mutbuf, at:u64, value:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, at + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0
"""

def request_source():
    source=POLICY
    source+='\ndef key_id(w:mutbuf, at:u64, size:u64) -> u64:\n'
    for index,name in enumerate(FIELDS,1):
        raw=name.encode()
        condition=' and '.join(f'getn(w, at + {i}, {len(raw[i:i+8])}) == {int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8))
        source+=f'    if size == {len(raw)} and {condition}:\n        return {index}\n'
    source+='    return 0\n'
    source+='\ndef reserved_environment(w:mutbuf, at:u64, size:u64) -> u64:\n'
    for name in ('CREDENTIALS_DIRECTORY','STATE_DIRECTORY','INVOCATION_ID','NOTIFY_SOCKET'):
        raw=name.encode();condition=' and '.join(f'getn(w, at + {i}, {len(raw[i:i+8])}) == {int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8))
        source+=f'    if size == {len(raw)} and {condition}:\n        return 1\n'
    source+='    return 0\n\ndef field_text(w:mutbuf, field:u64, at:u64) -> u64:\n'
    for index,name in enumerate(FIELDS):
        raw=('"'+name+'":').encode();source+=f'    if field == {index}:\n'
        for i in range(0,len(raw),8):
            chunk=raw[i:i+8];source+=f'        putn(w, at + {i}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
        source+=f'        return at + {len(raw)}\n'
    source+='    return at\n'
    constants={key:value for key,value in globals().items() if key.isupper() and type(value) is int}
    constants.update(NONE=(1<<64)-1,ARENA_MAGIC=5208772604367785521)
    for key in sorted(constants,key=len,reverse=True):
        source=re.sub(r'\b'+key+r'\b',str(constants[key]),source)
    return source

def decoder_source():
    source=base_json_source()
    old='if same_key(s, item & 4294967295, start) == 1:\n                return 4'
    assert source.count(old)==1
    return source.replace(old,old.replace('return 4','return 0'))

class RequestBuilder(LinkerBuilder):
    def expr(self,node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='word_store':
            args=[self.expr(value) for value in node.args]
            return self.op('buffer.store.u64.le',[args[0],self.cast(args[1],'usize'),self.cast(args[2],'u64')])
        return super().expr(node)

def document(source,module):
    nodes=ast.parse(source).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=RequestBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':functions})

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    for name,source in [('system_jobctl_request',request_source()),('system_jobctl_json',decoder_source())]:
        path=ROOT/'examples/hia_bootstrap'/(name+'.hepta');text=render_assembly(document(source,name))
        if args.check:assert path.read_text()==text,path
        else:path.write_text(text)
        print(name,len(text),flush=True)
if __name__=='__main__':main()
