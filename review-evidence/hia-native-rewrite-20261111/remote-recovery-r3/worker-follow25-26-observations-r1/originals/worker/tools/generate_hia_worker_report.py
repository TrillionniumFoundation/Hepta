"""Complete ordinary worker correlation/error/report ownership in HIA.

The private issuer supplies actual decoded Graphs and mechanical exception
observations. This component does not execute the still separate Agent service.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
HOST = BASE / 'Hepta-agent-edit-native'
sys.path.insert(0, str(HOST))
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools import generate_hia_agent_edit_apply_graph as graph
from tools import hia_agent_edit_source_views as shared

CONSTANTS = {
    'COMMAND': int.from_bytes(b'HIAWRC01', 'little'),
    'STATE': int.from_bytes(b'HIAWRW01', 'little'),
    'EVENT': int.from_bytes(b'HIAWRE01', 'little'),
    'GRAPH': int.from_bytes(b'HIAGRF01', 'little'),
    'BAD': 0xfffffffd, 'MAX': (1 << 64) - 1,
}
LITERALS = (
    'schema', 'tool', 'request_sha256', 'profile_sha256', 'catalog_sha256',
    'backend_sha256', 'worker_sha256', 'complete', 'response',
    'hia-agent-worker-report-v1', 'contract_version', 'hepta.hia.agent-native.v1',
    'request_id', 'status', 'rejected', 'error', 'code', 'phase', 'admission',
    'message', 'retry_action', 'details_artifact', 'type',
    'E_HIA_WORKER', 'E_HIA_REQUEST_UNKNOWN', 'correct_input', 'observe_original',
)
UNKNOWN_MESSAGE = ('worker could not attest the terminal result after entering the service; '
                   'observe the original job')

BODY = r'''
def worker_report(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        return BAD
    if get(w, 8) == 3:
        return BAD
    if get(w, 8) == 2:
        return refuse(w, 1)
    if length(r) != 192 or word(r, 0) != COMMAND or word(r, 16) == 0 or word(r, 24) == 0:
        return refuse(w, 2)
    if graph_shape(s, 0, length(s)) == 0 or word(r, 40) > 3 or word(r, 80) > 1:
        return refuse(w, 3)
    i = 104
    while i < 192:
        if word(r, i) != 0:
            return refuse(w, 4)
        i = i + 8
    if word(r, 80) == 0 and (word(r, 88) != 0 or word(r, 96) != 0):
        return refuse(w, 5)
    if get(w, 8) == 0:
        if word(r, 8) != 1 or word(r, 32) != 0:
            return refuse(w, 6)
        i = 0
        while i < 1024:
            if byte(w, i) != 0:
                return refuse(w, 7)
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
        put(w, 240, word(r, 72))
        put(w, 248, word(r, 40))
        copy_bytes(w, r, 448, 40, 152)
        copy_bytes(w, s, 640, 0, 64)
        if validate(s, w) == 0:
            return refuse(w, 8)
        put(w, 232, 1)
        if get(w, 248) == 1 or get(w, 248) == 2:
            if correlated(s, get(w, 200)) == 0:
                put(w, 232, 2)
            elif word(r, 80) == 0:
                put(w, 752, 1)
                return event(w, 2)
        elif get(w, 248) == 0:
            if correlated(s, get(w, 200)) == 0:
                return refuse(w, 9)
        put(w, 752, 2)
    else:
        if get(w, 0) != STATE or get(w, 8) != 1:
            return refuse(w, 10)
        if word(r, 16) != get(w, 16) or word(r, 24) != get(w, 24) or word(r, 32) != get(w, 32):
            return refuse(w, 11)
        if length(s) != get(w, 40):
            return refuse(w, 12)
        i = 0
        while i < 64:
            if byte(s, i) != byte(w, 640 + i):
                return refuse(w, 13)
            i = i + 1
        if get(w, 752) == 1:
            if word(r, 8) != 3 or word(r, 80) != 1:
                return refuse(w, 14)
            i = 0
            while i < 152:
                if i < 40 or i >= 64:
                    if byte(r, 40 + i) != byte(w, 448 + i):
                        return refuse(w, 15)
                i = i + 1
            copy_bytes(w, r, 488, 80, 24)
            put(w, 752, 2)
        else:
            if get(w, 752) != 2 or word(r, 8) != 2:
                return refuse(w, 16)
            i = 0
            while i < 152:
                if byte(r, 40 + i) != byte(w, 448 + i):
                    return refuse(w, 17)
                i = i + 1
    if get(w, 232) == 2:
        return stderr_result(s, w)
    put(w, 160, 0)
    put(w, 168, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    project(s, r, w)
    if get(w, 192) != 0 or sizes(w) == 0:
        return refuse(w, 18)
    if get(w, 152) > length(w):
        return event(w, 1)
    fill_range(w, 1024, get(w, 144), 0)
    if clone_graph(s, w, 0, 0, 0, 0) == 0:
        return refuse(w, 19)
    put(w, 160, 1)
    put(w, 168, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    project(s, r, w)
    if get(w, 192) != 0 or get(w, 168) != get(w, 56) or get(w, 176) != get(w, 64) or get(w, 184) != get(w, 80):
        return refuse(w, 20)
    put(w, 1024, GRAPH)
    put(w, 1032, get(w, 16))
    put(w, 1040, get(w, 120))
    put(w, 1048, get(w, 224))
    put(w, 1056, get(w, 128))
    put(w, 1064, get(w, 136))
    put(w, 1072, get(w, 144))
    put(w, 8, 2)
    return event(w, 0)

def valid_id(s:readbuf, value:u64) -> u64:
    return choose(value != 0 and value <= word(s, 16), 1, 0)

def validate(s:readbuf, w:mutbuf) -> u64:
    identities = get(w, 208)
    if gkind(s, identities) != 6 or amount(s, identities) != 3:
        return 0
    if canonical_digest(s, field(s, identities, L_worker_sha256)) == 0 or canonical_digest(s, field(s, identities, L_backend_sha256)) == 0 or canonical_digest(s, field(s, identities, L_catalog_sha256)) == 0:
        return 0
    if get(w, 248) == 3:
        if get(w, 200) != 0 or get(w, 216) != 0 or get(w, 240) != 0:
            return 0
        return 1
    if valid_id(s, get(w, 200)) == 0:
        return 0
    if get(w, 248) == 0:
        if valid_id(s, get(w, 216)) == 0 or get(w, 240) != 0:
            return 0
        return 1
    error = get(w, 240)
    if get(w, 216) != 0 or gkind(s, error) != 6:
        return 0
    if gkind(s, field(s, error, L_message)) != 4 or gkind(s, field(s, error, L_type)) != 4:
        return 0
    return 1

def canonical_digest(s:readbuf, id_:u64) -> u64:
    if gkind(s, id_) != 4 or word(s, id_ * 64 + 16) != 64 or word(s, id_ * 64 + 48) != 64:
        return 0
    begin = word(s, id_ * 64 + 8)
    if begin > length(s) or 64 > length(s) - begin:
        return 0
    i = 0
    while i < 64:
        ch = byte(s, begin + i)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 0
        i = i + 1
    return 1

def correlated(s:readbuf, id_:u64) -> u64:
    if gkind(s, id_) != 6:
        return 0
    return choose(field(s, id_, L_tool) != 0 and field(s, id_, L_request_sha256) != 0 and field(s, id_, L_profile_sha256) != 0 and field(s, id_, L_catalog_sha256) != 0, 1, 0)

def prefix(s:readbuf, w:mutbuf, id_:u64) -> u64:
    if gkind(s, id_) != 4:
        put(w, 192, 40)
        return 0
    begin = word(s, id_ * 64 + 8)
    size = word(s, id_ * 64 + 16)
    if begin > length(s) or size > length(s) - begin:
        put(w, 192, 41)
        return 0
    i = 0
    chars = 0
    while i < size and chars < 4096:
        ch = byte(s, begin + i)
        count_ = 1
        if ch >= 128:
            if ch >= 194 and ch <= 223:
                count_ = 2
            elif ch >= 224 and ch <= 239:
                count_ = 3
            elif ch >= 240 and ch <= 244:
                count_ = 4
            else:
                put(w, 192, 42)
                return 0
            if count_ > size - i:
                put(w, 192, 43)
                return 0
            j = 1
            while j < count_:
                part = byte(s, begin + i + j)
                if part < 128 or part > 191:
                    put(w, 192, 44)
                    return 0
                if j == 1:
                    if ch == 224 and part < 160:
                        put(w, 192, 45)
                        return 0
                    if (ch == 240 and part < 144) or (ch == 244 and part > 143):
                        put(w, 192, 46)
                        return 0
                j = j + 1
        i = i + count_
        chars = chars + 1
    if chars > word(s, id_ * 64 + 48) or (i == size and chars != word(s, id_ * 64 + 48)):
        put(w, 192, 47)
        return 0
    put(w, 768, i)
    put(w, 776, chars)
    return 1

def truncated(s:readbuf, w:mutbuf, source:u64) -> u64:
    if prefix(s, w, source) == 0:
        return 0
    size = get(w, 768)
    result = new_node(w, 4, 0, size, get(w, 776))
    if get(w, 160) != 0:
        copy_bytes(w, s, 1024 + get(w, 1024 + result * 64 + 8), word(s, source * 64 + 8), size)
    return result

def uuid(w:mutbuf, r:readbuf) -> u64:
    result = new_node(w, 4, 0, 39, 39)
    if get(w, 160) == 0:
        return result
    at = 1024 + get(w, 1024 + result * 64 + 8)
    store(w, at, 119)
    store(w, at + 1, 111)
    store(w, at + 2, 114)
    store(w, at + 3, 107)
    store(w, at + 4, 101)
    store(w, at + 5, 114)
    store(w, at + 6, 45)
    i = 0
    while i < 16:
        value = byte(r, 88 + i)
        if i == 6:
            value = (value & 15) | 64
        if i == 8:
            value = (value & 63) | 128
        high = value >> 4
        low = value & 15
        store(w, at + 7 + i * 2, high + choose(high < 10, 48, 87))
        store(w, at + 8 + i * 2, low + choose(low < 10, 48, 87))
        i = i + 1
    return result

def rejection(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    error = new_node(w, 6, 5, 0, 0)
    code = 0
    retry = 0
    message = 0
    if get(w, 248) == 2:
        code = literal(w, L_E_HIA_REQUEST_UNKNOWN)
        retry = literal(w, L_observe_original)
        message = unknown_message(w)
    else:
        observed = get(w, 240)
        code = field(s, observed, L_code)
        if code == 0:
            code = literal(w, L_E_HIA_WORKER)
        retry = field(s, observed, L_retry_action)
        if retry == 0:
            retry = literal(w, L_correct_input)
        source = field(s, observed, L_message)
        message = truncated(s, w, source)
        if get(w, 768) == 0:
            message = field(s, observed, L_type)
    pair(w, error, 0, literal(w, L_code), code)
    pair(w, error, 1, literal(w, L_phase), literal(w, L_admission))
    pair(w, error, 2, literal(w, L_message), message)
    pair(w, error, 3, literal(w, L_retry_action), retry)
    pair(w, error, 4, literal(w, L_details_artifact), new_node(w, 0, 0, 0, 0))
    response = new_node(w, 6, 4, 0, 0)
    pair(w, response, 0, literal(w, L_contract_version), literal(w, L_hepta_hia_agent_native_v1))
    pair(w, response, 1, literal(w, L_request_id), uuid(w, r))
    pair(w, response, 2, literal(w, L_status), literal(w, L_rejected))
    pair(w, response, 3, literal(w, L_error), error)
    return response

def project(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if get(w, 248) == 3:
        put(w, 224, get(w, 208))
        return 0
    response = get(w, 216)
    if get(w, 248) != 0:
        response = rejection(s, r, w)
    request = get(w, 200)
    identities = get(w, 208)
    report = new_node(w, 6, 9, 0, 0)
    pair(w, report, 0, literal(w, L_schema), literal(w, L_hia_agent_worker_report_v1))
    pair(w, report, 1, literal(w, L_tool), field(s, request, L_tool))
    pair(w, report, 2, literal(w, L_request_sha256), field(s, request, L_request_sha256))
    pair(w, report, 3, literal(w, L_profile_sha256), field(s, request, L_profile_sha256))
    pair(w, report, 4, literal(w, L_catalog_sha256), field(s, request, L_catalog_sha256))
    pair(w, report, 5, literal(w, L_backend_sha256), field(s, identities, L_backend_sha256))
    pair(w, report, 6, literal(w, L_worker_sha256), field(s, identities, L_worker_sha256))
    pair(w, report, 7, literal(w, L_complete), new_node(w, 1, 0, 0, 1))
    pair(w, report, 8, literal(w, L_response), response)
    put(w, 224, report)
    return 0

def stderr_result(s:readbuf, w:mutbuf) -> u32:
    source = field(s, get(w, 240), L_message)
    if prefix(s, w, source) == 0:
        return refuse(w, 48)
    size = get(w, 768)
    put(w, 144, size + 1)
    put(w, 152, 1025 + size)
    if get(w, 152) > length(w):
        return event(w, 1)
    copy_bytes(w, s, 1024, word(s, source * 64 + 8), size)
    store(w, 1024 + size, 10)
    put(w, 8, 2)
    return event(w, 0)

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
    put(w, 344, choose(get(w, 232) == 2, 2, 0))
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
    for row in json.loads((ROOT / 'checkpoints/baseline-r1/source.json').read_bytes()):
        if row['path'].endswith(('generate_hia_agent_edit_apply_graph.py',
                                 'generate_hia_graph_merge.py', 'hia_agent_edit_source_views.py')):
            assert sha256(Path(row['path']).read_bytes()).hexdigest() == row['sha256']
    labels = {}
    for value in LITERALS:
        raw = value.encode('ascii')
        assert len(raw) <= 32
        labels['L_' + value.replace('.', '_').replace('-', '_')] = [
            len(raw), *(int.from_bytes(raw[i:i + 8], 'little') for i in (0, 8, 16, 24))]

    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node

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

    raw = UNKNOWN_MESSAGE.encode()
    lines = ['def unknown_message(w:mutbuf) -> u64:',
             f'    result = new_node(w, 4, 0, {len(raw)}, {len(raw)})',
             '    if get(w, 160) != 0:',
             '        at = 1024 + get(w, 1024 + result * 64 + 8)']
    whole = len(raw) // 8 * 8
    for at in range(0, whole, 8):
        lines.append(f'        put(w, at + {at}, {int.from_bytes(raw[at:at + 8], "little")})')
    for at in range(whole, len(raw)):
        lines.append(f'        store(w, at + {at}, {raw[at]})')
    lines.append('    return result')
    own = Expand().visit(ast.parse(BODY + '\n'.join(lines) + '\n')).body
    old = {node.name: node for node in ast.parse(graph.source_program()).body}
    keep = ('gkind', 'amount', 'element', 'text_is', 'field', 'sizes', 'new_node',
            'set_edge', 'pair', 'literal', 'graph_shape', 'clone_graph',
            'clone_container', 'clone_scalar', 'word', 'get', 'put')
    tree = ast.Module(body=own + [old[name] for name in keep], type_ignores=[])
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i + 1) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    params = [{'name': 'v0', 'type': 'readbuf'}, {'name': 'v1', 'type': 'mutbuf'},
              {'name': 'v2', 'type': 'mutbuf'}]
    functions = [{'name': 'f0', 'params': params, 'returns': ['u32'],
                  'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': [
        {'id': 'b0', 'params': params, 'ops': [
            {'op': 'borrow.read', 'args': ['v1'], 'out': [{'name': 'v3', 'type': 'readbuf'}], 'attrs': {}},
            {'op': 'call', 'args': ['v0', 'v3', 'v2'], 'out': [{'name': 'v4', 'type': 'u32'}],
             'attrs': {'function': names['worker_report']}},
            {'op': 'loan.end', 'args': ['v3'], 'out': [], 'attrs': {}}],
         'term': {'op': 'ret', 'values': ['v4']}}]}]
    for node in nodes:
        builder = shared.CopyBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'agent_worker_report', 'functions': functions})


if __name__ == '__main__':
    value = document()
    raw = render_assembly(value).encode()
    output = ROOT / 'examples/hia_bootstrap/agent_worker_report.hiaasm'
    output.write_bytes(raw)
    print(json.dumps(dict(path=str(output), bytes=len(raw), sha256=sha256(raw).hexdigest(),
                         functions=len(value['functions']),
                         blocks=sum(len(fn['blocks']) for fn in value['functions']),
                         instructions=sum(len(block['ops']) for fn in value['functions'] for block in fn['blocks']),
                         max_function_blocks=max(len(fn['blocks']) for fn in value['functions']),
                         max_block_parameters=max(len(block['params']) for fn in value['functions'] for block in fn['blocks'])),
                     sort_keys=True))
