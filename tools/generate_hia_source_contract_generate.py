"""Author the HIA source-contract producer over a captured source inventory.

The producer owns JSON admission, exact source-map replacement, path ordering,
self-entry exclusion and bounded emission. It is not a qualification receipt:
metadata authority and physical file custody remain with the native caller.
"""
from pathlib import Path
import ast,copy
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document

ROOT=Path(__file__).resolve().parents[1]
SOURCE='examples/hia_bootstrap/source_contract_generate.hepta'
CONTRACT_PATH='docs/HIA_SELFHOST_CORE_SUPPORT.json'
PROGRAM=r'''
def source_contract_generate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 50 or length(s) > 8388608 or length(o) != 8388608 or length(w) < 32768:
        return 4294967293
    if uint(s, 0, 8) != CONTRACT_MAGIC or uint(s, 24, 8) != 0:
        return 4294967295
    metadata = uint(s, 8, 8)
    inventory = uint(s, 16, 8)
    if metadata < 2 or inventory < 16 or metadata > length(s) - 32 or inventory != length(s) - 32 - metadata:
        return 4294967295
    meta_put(w, 48, 262144)
    meta_put(w, 56, 128)
    if widen(meta_preflight(s, o, w, metadata)) != 0:
        return 4294967295
    root = whitespace(s, 32)
    if byte(s, root) != 123:
        return 4294967295
    identity = member(s, w, root, 1, metadata)
    if identity == 0 or byte(s, identity & 4294967295) != 123:
        return 4294967295
    files = member(s, w, identity & 4294967295, 2, metadata)
    if files == 0 or byte(s, files & 4294967295) != 123:
        return 4294967295
    prefix = (files & 4294967295) - 32
    suffix = 32 + metadata - (files >> 32)
    needed = inventory_admit(s, w, 32 + metadata, prefix + suffix + 2)
    if needed == 0:
        return 4294967295
    if needed > length(o):
        return 4294967294
    at = copy(s, o, 0, 32, prefix)
    store(o, at, 123)
    at = at + 1
    cursor = 48 + metadata
    index = 0
    count = uint(s, 40 + metadata, 8)
    emitted = 0
    while index < count:
        size = uint(s, cursor, 8)
        if contract_name(s, cursor + 40, size) == 0:
            if emitted != 0:
                store(o, at, 44)
                at = at + 1
            store(o, at, 34)
            at = copy(s, o, at + 1, cursor + 40, size)
            store(o, at, 34)
            store(o, at + 1, 58)
            store(o, at + 2, 34)
            at = hex_digest(s, o, cursor + 8, at + 3)
            store(o, at, 34)
            at = at + 1
            emitted = emitted + 1
        cursor = cursor + 40 + size
        index = index + 1
    store(o, at, 125)
    at = copy(s, o, at + 1, files >> 32, suffix)
    if at != needed:
        return 4294967295
    return at

def widen(value:u32) -> u64:
    return value

def inventory_admit(s:readbuf, w:mutbuf, start:u64, needed:u64) -> u64:
    if uint(s, start, 8) != INVENTORY_MAGIC:
        return 0
    count = uint(s, start + 8, 8)
    if count < 1 or count > 4096:
        return 0
    cursor = start + 16
    index = 0
    previous = 0
    previous_size = 0
    contracts = 0
    emitted = 0
    while index < count:
        if cursor > length(s) or length(s) - cursor < 40:
            return 0
        size = uint(s, cursor, 8)
        if size < 1 or size > 4095 or size > length(s) - cursor - 40:
            return 0
        at = cursor + 40
        if relative(s, at, size) == 0:
            return 0
        if index != 0 and raw_order(s, previous, previous_size, at, size) != 1:
            return 0
        if contract_name(s, at, size) == 1:
            contracts = contracts + 1
        else:
            needed = needed + size + 69 + choose(emitted == 0, 0, 1)
            emitted = emitted + 1
        previous = at
        previous_size = size
        cursor = at + size
        index = index + 1
    return choose(cursor == length(s) and contracts == 1, needed, 0)

def relative(s:readbuf, at:u64, size:u64) -> u64:
    index = 0
    component = 0
    while index < size:
        ch = byte(s, at + index)
        if ch == 47:
            if component == 0 or (component == 1 and byte(s, at + index - 1) == 46) or (component == 2 and byte(s, at + index - 1) == 46 and byte(s, at + index - 2) == 46):
                return 0
            component = 0
        else:
            if (ch < 48 or ch > 57) and (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 45 and ch != 46 and ch != 95:
                return 0
            component = component + 1
        index = index + 1
    if component == 0 or (component == 1 and byte(s, at + size - 1) == 46) or (component == 2 and byte(s, at + size - 1) == 46 and byte(s, at + size - 2) == 46):
        return 0
    return 1

def raw_order(s:readbuf, left:u64, left_size:u64, right:u64, right_size:u64) -> u64:
    index = 0
    while index < left_size and index < right_size:
        a = byte(s, left + index)
        b = byte(s, right + index)
        if a != b:
            return choose(a < b, 1, 2)
        index = index + 1
    if left_size == right_size:
        return 0
    return choose(left_size < right_size, 1, 2)

def member(s:readbuf, w:mutbuf, root:u64, key:u64, metadata:u64) -> u64:
    at = whitespace(s, root + 1)
    while byte(s, at) != 125:
        token = key_token(s, w, at, metadata)
        at = whitespace(s, skip(s, at))
        at = whitespace(s, at + 1)
        end = skip(s, at)
        if token == key:
            return at | (end << 32)
        at = whitespace(s, end)
        if byte(s, at) == 44:
            at = whitespace(s, at + 1)
    return 0

def key_token(s:readbuf, w:mutbuf, start:u64, metadata:u64) -> u64:
    at = start - 31
    size = 0
    while at < metadata:
        unit = meta_decoded(s, at, metadata)
        ch = unit & 4294967295
        at = unit >> 32
        if ch == 1114112:
            return key_value(w, size)
        if ch >= 128 or size >= 32:
            return 0
        store(w, 16384 + size, ch)
        size = size + 1
    return 0

def whitespace(s:readbuf, at:u64) -> u64:
    while at < length(s):
        ch = byte(s, at)
        if ch != 32 and ch != 9 and ch != 10 and ch != 13:
            return at
        at = at + 1
    return at

def skip(s:readbuf, at:u64) -> u64:
    first = byte(s, at)
    if first == 34:
        at = at + 1
        while at < length(s):
            ch = byte(s, at)
            at = at + 1
            if ch == 34:
                return at
            if ch == 92:
                at = at + 1
        return at
    if first == 91 or first == 123:
        depth = 1
        at = at + 1
        while depth != 0:
            ch = byte(s, at)
            if ch == 34:
                at = skip(s, at)
            else:
                if ch == 91 or ch == 123:
                    depth = depth + 1
                if ch == 93 or ch == 125:
                    depth = depth - 1
                at = at + 1
        return at
    while at < length(s):
        ch = byte(s, at)
        if ch == 32 or ch == 9 or ch == 10 or ch == 13 or ch == 44 or ch == 93 or ch == 125:
            return at
        at = at + 1
    return at

def uint(s:readbuf, at:u64, size:u64) -> u64:
    value = 0
    index = 0
    while index < size:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def word(w:mutbuf, at:u64, size:u64) -> u64:
    value = 0
    index = 0
    while index < size:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def copy(s:readbuf, o:mutbuf, at:u64, start:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, at + index, byte(s, start + index))
        index = index + 1
    return at + size

def hex_digest(s:readbuf, o:mutbuf, start:u64, at:u64) -> u64:
    index = 0
    while index < 32:
        ch = byte(s, start + index)
        high = ch >> 4
        low = ch & 15
        store(o, at + index * 2, choose(high < 10, high + 48, high + 87))
        store(o, at + index * 2 + 1, choose(low < 10, low + 48, low + 87))
        index = index + 1
    return at + 64
'''

def program():
    author=(ROOT/'tools/generate_hia_json_preflight.py').read_text()
    tree=ast.parse(author)
    source=next(n.value.value for n in tree.body if isinstance(n,ast.Assign) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str) and 'def preflight' in n.value.value)
    nodes=ast.parse(source).body
    names={n.name:'meta_'+n.name for n in nodes}
    borrowed={n.name for n in nodes if any(a.arg=='s' for a in n.args.args)}
    class Slice(ast.NodeTransformer):
        def visit_FunctionDef(self,node):
            node=copy.deepcopy(node);old=node.name;node.name=names[old]
            if old in borrowed:node.args.args.append(ast.arg(arg='source_limit',annotation=ast.Name(id='u64',ctx=ast.Load())))
            return self.generic_visit(node)
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Name):
                name=node.func.id
                if name=='length' and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':return ast.Name(id='source_limit',ctx=ast.Load())
                if name=='byte' and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':node.args[1]=ast.BinOp(left=node.args[1],op=ast.Add(),right=ast.Constant(value=32))
                if name in names:
                    node.func.id=names[name]
                    if name in borrowed:node.args.append(ast.Name(id='source_limit',ctx=ast.Load()))
            return node
    helpers='\n\n'.join(ast.unparse(ast.fix_missing_locations(Slice().visit(n))) for n in nodes)
    key=['def key_value(w:mutbuf, size:u64) -> u64:']
    for index,name in enumerate(['source_identity','files'],1):
        raw=name.encode();parts=[f'(word(w, {16384+at}, {len(raw[at:at+8])}) ^ {int.from_bytes(raw[at:at+8],"little")})' for at in range(0,len(raw),8)]
        key.extend((f'    if size == {len(raw)}:',f'        if ({" | ".join(parts)}) == 0:',f'            return {index}'))
    key.append('    return 0')
    raw=CONTRACT_PATH.encode();name=['def contract_name(s:readbuf, at:u64, size:u64) -> u64:',f'    if size != {len(raw)}:','        return 0']
    parts=[f'(uint(s, at + {at}, {len(raw[at:at+8])}) ^ {int.from_bytes(raw[at:at+8],"little")})' for at in range(0,len(raw),8)]
    name.append('    return choose(('+' | '.join(parts)+') == 0, 1, 0)')
    body=PROGRAM.replace('CONTRACT_MAGIC',str(int.from_bytes(b'HIASCG01','little'))).replace('INVENTORY_MAGIC',str(int.from_bytes(b'HIASPI01','little')))
    return '\n\n'.join((body,helpers,'\n'.join(key),'\n'.join(name)))

def render():return render_assembly(document(program(),'source_contract_generate'))
if __name__=='__main__':(ROOT/SOURCE).write_text(render())
