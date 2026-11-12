"""Native single/batch response policy, complete patch and pending receipt data.

Inputs are actual immutable Graph leases of admitted base, native reconstructed
query and normalized decoded response. The public coordinator must compare the
untrusted query wire first, enforce original response decode/byte order, invoke
the complete patch/Core owner, and publish metadata only after final admission.
This component does not make a digest or private header into that authority.
"""
from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools import hia_agent_edit_source_views as shared
from tools import generate_hia_graph_merge as merger

CONSTANTS = {'COMMAND': int.from_bytes(b'HIAQAC01', 'little'),
             'STATE': int.from_bytes(b'HIAQAW01', 'little'),
             'EVENT': int.from_bytes(b'HIAQAE01', 'little'),
             'GRAPH': int.from_bytes(b'HIAGRF01', 'little'),
             'BAD': 0xfffffffd, 'MAX': (1 << 64) - 1}
LITERALS = ('edits', 'site', 'changes', 'sites', 'query', 'fields', 'context', 'operation',
            'selector', 'function', 'block', 'operation_index', 'schema', 'base_sha256',
            'action', 'replace_operation', 'index', 'expected_sha256', 'hepta.hia.patch.v1',
            'query_sha256', 'response_sha256', 'response_bytes', 'context_reconstructed',
            'entire_module_reverified', 'intermediate_candidates_admitted')
SOURCE = r'''
def apply_graph(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        return BAD
    if get(w, 8) == 3:
        return BAD
    if get(w, 8) == 2:
        return refuse(w, 1)
    if length(r) != 192 or word(r, 0) != COMMAND or word(r, 16) == 0 or word(r, 24) == 0:
        return refuse(w, 2)
    if graph_shape(s, 0, length(s)) == 0:
        return refuse(w, 3)
    if word(r, 40) == 0 or word(r, 40) > 2:
        return refuse(w, 4)
    i = 48
    while i < 72:
        if word(r, i) == 0 or word(r, i) > word(s, 16):
            return refuse(w, 5)
        i = i + 8
    i = 80
    while i < 128:
        if word(r, i) != 0:
            return refuse(w, 6)
        i = i + 8
    maximum = 16384
    if word(r, 40) == 2:
        maximum = 65536
    if word(r, 72) > maximum:
        return refuse(w, 7)
    if get(w, 8) == 0:
        if word(r, 8) != 1 or word(r, 32) != 0:
            return refuse(w, 8)
        i = 0
        while i < 1024:
            if byte(w, i) != 0:
                return refuse(w, 9)
            i = i + 1
        put(w, 0, STATE)
        put(w, 8, 1)
        put(w, 16, word(r, 16))
        put(w, 24, word(r, 24))
        put(w, 40, length(s))
        put(w, 72, word(s, 16))
        put(w, 88, word(s, 32))
        put(w, 104, word(s, 40))
        put(w, 200, word(r, 48))
        put(w, 208, word(r, 56))
        put(w, 216, word(r, 64))
        put(w, 248, word(r, 40))
        copy_bytes(w, r, 448, 40, 152)
        copy_bytes(w, s, 640, 0, 64)
        semantic = validate(s, w)
        if semantic != 0:
            put(w, 192, semantic)
            put(w, 8, 2)
            return event(w, 2)
        put(w, 160, 0)
        project(s, r, w)
        if sizes(w) == 0:
            return refuse(w, 10)
    else:
        if get(w, 0) != STATE or get(w, 8) != 1 or word(r, 8) != 2:
            return refuse(w, 11)
        if word(r, 16) != get(w, 16) or word(r, 24) != get(w, 24) or word(r, 32) != get(w, 32):
            return refuse(w, 12)
        if length(s) != get(w, 40):
            return refuse(w, 13)
        i = 0
        while i < 152:
            if byte(r, 40 + i) != byte(w, 448 + i):
                return refuse(w, 14)
            i = i + 1
        i = 0
        while i < 64:
            if byte(s, i) != byte(w, 640 + i):
                return refuse(w, 15)
            i = i + 1
    if get(w, 152) > length(w):
        return event(w, 1)
    fill_range(w, 1024, get(w, 144), 0)
    if clone_graph(s, w, 0, 0, 0, 0) == 0:
        return refuse(w, 16)
    put(w, 160, 1)
    put(w, 168, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    project(s, r, w)
    if get(w, 168) != get(w, 56) or get(w, 176) != get(w, 64) or get(w, 184) != get(w, 80):
        return refuse(w, 17)
    put(w, 1024, GRAPH)
    put(w, 1032, get(w, 16))
    put(w, 1040, get(w, 120))
    put(w, 1048, get(w, 224))
    put(w, 1056, get(w, 128))
    put(w, 1064, get(w, 136))
    put(w, 1072, get(w, 144))
    put(w, 8, 2)
    return event(w, 0)

def gkind(s:readbuf, id_:u64) -> u64:
    if id_ == 0 or id_ > word(s, 16):
        return MAX
    return word(s, id_ * 64)

def amount(s:readbuf, id_:u64) -> u64:
    if id_ == 0 or id_ > word(s, 16):
        return 0
    return word(s, id_ * 64 + 32)

def element(s:readbuf, id_:u64, index:u64) -> u64:
    kind = gkind(s, id_)
    if kind != 5 and kind != 6 and kind != 7:
        return 0
    count_ = amount(s, id_)
    if kind == 6:
        count_ = count_ * 2
    first = word(s, id_ * 64 + 24)
    if first > word(s, 32) or count_ > word(s, 32) - first or index >= count_:
        return 0
    return word(s, 64 + word(s, 16) * 64 + (first + index) * 8)

def text_equal(s:readbuf, a:u64, b:u64) -> u64:
    if gkind(s, a) != 4 or gkind(s, b) != 4:
        return 0
    size = word(s, a * 64 + 16)
    if size != word(s, b * 64 + 16):
        return 0
    left = word(s, a * 64 + 8)
    right = word(s, b * 64 + 8)
    if left > length(s) or size > length(s) - left or right > length(s) or size > length(s) - right:
        return 0
    i = 0
    while i < size:
        if byte(s, left + i) != byte(s, right + i):
            return 0
        i = i + 1
    return 1

def text_is(s:readbuf, id_:u64, size:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    if gkind(s, id_) != 4 or word(s, id_ * 64 + 16) != size:
        return 0
    start = word(s, id_ * 64 + 8)
    if start > length(s) or size > length(s) - start:
        return 0
    i = 0
    while i < size:
        part = a
        if i >= 8:
            part = b
        if i >= 16:
            part = c
        if i >= 24:
            part = d
        if byte(s, start + i) != ((part >> ((i & 7) * 8)) & 255):
            return 0
        i = i + 1
    return 1

def field(s:readbuf, id_:u64, size:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    if gkind(s, id_) != 6:
        return 0
    i = 0
    while i < amount(s, id_):
        if text_is(s, element(s, id_, i * 2), size, a, b, c, d) != 0:
            return element(s, id_, i * 2 + 1)
        i = i + 1
    return 0

def lookup(s:readbuf, id_:u64, key:u64) -> u64:
    i = 0
    while i < amount(s, id_):
        if text_equal(s, element(s, id_, i * 2), key) != 0:
            return element(s, id_, i * 2 + 1)
        i = i + 1
    return 0

def small_integer(s:readbuf, id_:u64) -> u64:
    if gkind(s, id_) != 2 or word(s, id_ * 64 + 48) != 0:
        return MAX
    size = word(s, id_ * 64 + 16)
    start = word(s, id_ * 64 + 8)
    if size > 8 or start > length(s) or size > length(s) - start:
        return MAX
    value = 0
    i = 0
    while i < size:
        value = value | (byte(s, start + i) << (i * 8))
        i = i + 1
    return value

def changes_valid(s:readbuf, changes:u64, query:u64) -> u64:
    if gkind(s, changes) != 6 or amount(s, changes) == 0:
        return 0
    fields = field(s, query, L_fields)
    if gkind(s, fields) != 5:
        return 0
    i = 0
    while i < amount(s, changes):
        key = element(s, changes, i * 2)
        found = 0
        j = 0
        while j < amount(s, fields):
            if text_equal(s, key, element(s, fields, j)) != 0:
                found = 1
            j = j + 1
        if found == 0:
            return 0
        i = i + 1
    return 1

def validate(s:readbuf, w:mutbuf) -> u64:
    query = get(w, 208)
    response = get(w, 216)
    if get(w, 248) == 1:
        if changes_valid(s, response, query) == 0:
            return 1
        return 0
    if gkind(s, response) != 6 or amount(s, response) != 1:
        return 2
    edits = field(s, response, L_edits)
    if edits == 0:
        return 2
    sites = field(s, query, L_sites)
    if gkind(s, sites) != 5 or amount(s, sites) == 0 or amount(s, sites) > 16:
        return 256
    if gkind(s, edits) != 5 or amount(s, edits) != amount(s, sites):
        return 3
    seen = 0
    i = 0
    while i < amount(s, edits):
        item = element(s, edits, i)
        index_node = field(s, item, L_site)
        changes = field(s, item, L_changes)
        if gkind(s, item) != 6 or amount(s, item) != 2 or index_node == 0 or changes == 0:
            return 4
        index = small_integer(s, index_node)
        if index >= amount(s, sites):
            return 5
        bit = 1 << index
        if (seen & bit) != 0:
            return 5
        seen = seen | bit
        nested = field(s, element(s, sites, index), L_query)
        if changes_valid(s, changes, nested) == 0:
            return 6
        i = i + 1
    return 0

def sizes(w:mutbuf) -> u64:
    put(w, 56, get(w, 168))
    put(w, 64, get(w, 176))
    put(w, 80, get(w, 184))
    if get(w, 56) > MAX - get(w, 72) or get(w, 64) > MAX - get(w, 88) or get(w, 80) > MAX - get(w, 104):
        return 0
    nodes = get(w, 56) + get(w, 72)
    edges = get(w, 64) + get(w, 88)
    scalars = get(w, 80) + get(w, 104)
    if nodes > (MAX - 64) >> 6:
        return 0
    base = 64 + nodes * 64
    if edges > (MAX - base) >> 3:
        return 0
    base = base + edges * 8
    if scalars > MAX - base or base + scalars > MAX - 1024:
        return 0
    put(w, 120, nodes)
    put(w, 128, edges)
    put(w, 136, scalars)
    put(w, 144, base + scalars)
    put(w, 152, 1024 + base + scalars)
    return 1

def new_node(w:mutbuf, kind:u64, arity:u64, scalar_size:u64, aux:u64) -> u64:
    id_ = get(w, 72) + get(w, 168) + 1
    first = get(w, 88) + get(w, 176)
    scalar = get(w, 104) + get(w, 184)
    put(w, 168, get(w, 168) + 1)
    put(w, 176, get(w, 176) + arity * choose(kind == 6, 2, 1))
    put(w, 184, get(w, 184) + scalar_size)
    if get(w, 160) != 0:
        at = 1024 + id_ * 64
        put(w, at, kind)
        put(w, at + 48, aux)
        if kind == 5 or kind == 6:
            put(w, at + 24, first)
            put(w, at + 32, arity)
            put(w, at + 40, id_)
        elif kind == 2 or kind == 4:
            put(w, at + 8, 64 + get(w, 120) * 64 + get(w, 128) * 8 + scalar)
            put(w, at + 16, scalar_size)
    return id_

def set_edge(w:mutbuf, parent:u64, index:u64, child:u64) -> u64:
    if get(w, 160) != 0:
        first = get(w, 1024 + parent * 64 + 24)
        put(w, 1088 + get(w, 120) * 64 + (first + index) * 8, child)
    return 0

def pair(w:mutbuf, parent:u64, index:u64, key:u64, value:u64) -> u64:
    set_edge(w, parent, index * 2, key)
    set_edge(w, parent, index * 2 + 1, value)
    return 0

def literal(w:mutbuf, size:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    id_ = new_node(w, 4, 0, size, size)
    if get(w, 160) == 0:
        return id_
    at = 1024 + get(w, 1024 + id_ * 64 + 8)
    i = 0
    while i < size:
        part = a
        if i >= 8:
            part = b
        if i >= 16:
            part = c
        if i >= 24:
            part = d
        store(w, at + i, (part >> ((i & 7) * 8)) & 255)
        i = i + 1
    return id_

def integer(w:mutbuf, value:u64) -> u64:
    size = 0
    rest = value
    while rest != 0:
        size = size + 1
        rest = rest >> 8
    id_ = new_node(w, 2, 0, size, 0)
    if get(w, 160) != 0:
        at = 1024 + get(w, 1024 + id_ * 64 + 8)
        i = 0
        while i < size:
            store(w, at + i, (value >> (i * 8)) & 255)
            i = i + 1
    return id_

def digest(r:readbuf, w:mutbuf, offset:u64) -> u64:
    id_ = new_node(w, 4, 0, 64, 64)
    if get(w, 160) == 0:
        return id_
    at = 1024 + get(w, 1024 + id_ * 64 + 8)
    i = 0
    while i < 64:
        value = byte(r, offset + (i >> 1))
        if (i & 1) == 0:
            value = value >> 4
        value = value & 15
        store(w, at + i, value + choose(value < 10, 48, 87))
        i = i + 1
    return id_

def replacement(s:readbuf, w:mutbuf, nested:u64, changes:u64) -> u64:
    context = field(s, nested, L_context)
    original = field(s, context, L_operation)
    operation = new_node(w, 6, amount(s, original), 0, 0)
    i = 0
    while i < amount(s, original):
        key = element(s, original, i * 2)
        value = lookup(s, changes, key)
        if value == 0:
            value = element(s, original, i * 2 + 1)
        pair(w, operation, i, key, value)
        i = i + 1
    selector = field(s, nested, L_selector)
    edit = new_node(w, 6, 5, 0, 0)
    pair(w, edit, 0, literal(w, L_action), literal(w, L_replace_operation))
    pair(w, edit, 1, literal(w, L_function), field(s, selector, L_function))
    pair(w, edit, 2, literal(w, L_block), field(s, selector, L_block))
    pair(w, edit, 3, literal(w, L_index), field(s, context, L_operation_index))
    pair(w, edit, 4, literal(w, L_operation), operation)
    return edit

def edits(s:readbuf, w:mutbuf) -> u64:
    query = get(w, 208)
    response = get(w, 216)
    if get(w, 248) == 1:
        list_ = new_node(w, 5, 1, 0, 0)
        set_edge(w, list_, 0, replacement(s, w, query, response))
        return list_
    sites = field(s, query, L_sites)
    edits_ = field(s, response, L_edits)
    list_ = new_node(w, 5, amount(s, edits_), 0, 0)
    i = 0
    while i < amount(s, edits_):
        item = element(s, edits_, i)
        index = small_integer(s, field(s, item, L_site))
        nested = field(s, element(s, sites, index), L_query)
        set_edge(w, list_, i, replacement(s, w, nested, field(s, item, L_changes)))
        i = i + 1
    return list_

def metadata(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    query = get(w, 208)
    root = new_node(w, 6, 7, 0, 0)
    pair(w, root, 0, literal(w, L_schema), field(s, query, L_schema))
    if get(w, 248) == 1:
        pair(w, root, 1, literal(w, L_selector), field(s, query, L_selector))
    else:
        pair(w, root, 1, literal(w, L_sites), integer(w, amount(s, field(s, query, L_sites))))
    pair(w, root, 2, literal(w, L_query_sha256), digest(r, w, 128))
    pair(w, root, 3, literal(w, L_response_bytes), integer(w, word(r, 72)))
    pair(w, root, 4, literal(w, L_response_sha256), digest(r, w, 160))
    if get(w, 248) == 1:
        pair(w, root, 5, literal(w, L_context_reconstructed), new_node(w, 1, 0, 0, 1))
    else:
        pair(w, root, 5, literal(w, L_intermediate_candidates_admitted), new_node(w, 1, 0, 0, 0))
    pair(w, root, 6, literal(w, L_entire_module_reverified), new_node(w, 1, 0, 0, 1))
    return root

def project(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    root = new_node(w, 5, 2, 0, 0)
    envelope = new_node(w, 5, 2, 0, 0)
    patch_ = new_node(w, 6, 3, 0, 0)
    pair(w, patch_, 0, literal(w, L_schema), literal(w, L_hepta_hia_patch_v1))
    pair(w, patch_, 1, literal(w, L_expected_sha256), field(s, get(w, 208), L_base_sha256))
    pair(w, patch_, 2, literal(w, L_edits), edits(s, w))
    set_edge(w, envelope, 0, get(w, 200))
    set_edge(w, envelope, 1, patch_)
    meta = metadata(s, r, w)
    set_edge(w, root, 0, envelope)
    set_edge(w, root, 1, meta)
    put(w, 224, root)
    put(w, 232, envelope)
    put(w, 240, meta)
    return 0

def event(w:mutbuf, action:u64) -> u32:
    if get(w, 32) == MAX:
        put(w, 8, 3)
        return BAD
    put(w, 32, get(w, 32) + 1)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, 16))
    put(w, 280, get(w, 24))
    put(w, 288, get(w, 32))
    put(w, 296, get(w, 152))
    put(w, 304, 1024)
    put(w, 312, get(w, 144))
    put(w, 320, get(w, 192))
    put(w, 328, get(w, 224))
    put(w, 336, get(w, 232))
    put(w, 344, get(w, 240))
    put(w, 352, get(w, 248))
    put(w, 360, 0)
    put(w, 368, 0)
    put(w, 376, 0)
    return 384

def refuse(w:mutbuf, reason:u64) -> u32:
    put(w, 8, 3)
    put(w, 192, reason)
    event(w, 3)
    return BAD
'''

def source_program():
    assert sha256(Path(shared.__file__).read_bytes()).hexdigest() == '555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c'
    def packed(value):
        raw = value.encode('ascii'); assert len(raw) <= 32
        return [len(raw), *(int.from_bytes(raw[i:i + 8], 'little') for i in (0, 8, 16, 24))]
    labels = {'L_' + v.replace('.', '_').replace('-', '_'): packed(v) for v in LITERALS}
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node) if node.id in CONSTANTS else node
        def visit_Call(self, node):
            node = self.generic_visit(node)
            args = []
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in labels:
                    args.extend(ast.Constant(v) for v in labels[arg.id])
                else:
                    args.append(arg)
            node.args = args
            return node
    own = Expand().visit(ast.parse(SOURCE)).body
    old = {n.name: n for n in ast.parse(merger.source_program()).body}
    class MoveOutput(ast.NodeTransformer):
        def visit_Constant(self, node):
            if type(node.value) is int and node.value in (512, 576):
                return ast.copy_location(ast.Constant(node.value + 512), node)
            return node
    clone = [MoveOutput().visit(old[n]) for n in ('graph_shape', 'clone_graph', 'clone_container', 'clone_scalar')]
    tree = ast.Module(body=own + clone + [old[n] for n in ('word', 'get', 'put')], type_ignores=[])
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i + 1) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    params = [{'name': 'v0', 'type': 'readbuf'}, {'name': 'v1', 'type': 'mutbuf'}, {'name': 'v2', 'type': 'mutbuf'}]
    functions = [{'name': 'f0', 'params': params, 'returns': ['u32'], 'effects': ['read', 'write', 'trap'],
        'entry': 'b0', 'blocks': [{'id': 'b0', 'params': params, 'ops': [
            {'op': 'borrow.read', 'args': ['v1'], 'out': [{'name': 'v3', 'type': 'readbuf'}], 'attrs': {}},
            {'op': 'call', 'args': ['v0', 'v3', 'v2'], 'out': [{'name': 'v4', 'type': 'u32'}], 'attrs': {'function': names['apply_graph']}},
            {'op': 'loan.end', 'args': ['v3'], 'out': [], 'attrs': {}}], 'term': {'op': 'ret', 'values': ['v4']}}]}]
    for node in nodes:
        builder = shared.CopyBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_edit_apply_graph', 'functions': functions})

if __name__ == '__main__':
    doc = document()
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_edit_apply_graph.hiaasm'
    path.write_text(render_assembly(doc))
    print(path.name, path.stat().st_size, len(doc['functions']), sum(len(f['blocks']) for f in doc['functions']),
          max(len(f['blocks']) for f in doc['functions']), sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))
