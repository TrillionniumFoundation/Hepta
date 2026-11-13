"""Explicit native HIA Agent editing-view selection and fact transport.

Core JSON admission, verification, immutable objects, names, query hashing and
patch publication remain host-owned. SSA slicing, FIFO CFG propagation,
affected branch regions, dependency closure and view budgets execute in HIA.
There is no reference-algorithm fallback after explicit operator selection.
"""
from __future__ import annotations
import ctypes
import struct
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

from .hia_agent_store import _agent_resource_path
SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_slice.hiaasm')
SCHEMA = 'hepta.hia.agent-slice-native.v1'
MAGIC = int.from_bytes(b'HIASLC01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASLR01', 'little')
MAX_BYTES = 8 << 20
NONE = (1 << 64) - 1
ERRORS = {
    0xfffffffc: 'cross-block SSA cycle reaches selected block; use full-module view',
    0xfffffffb: 'transitive CFG view exceeds bounded block budget',
    0xfffffffa: 'transitive SSA view exceeds bounded operation budget',
}


def encode_function(fn, source_block, selected_index):
    """Encode immutable verified facts; perform no slicing/reachability query."""
    blocks, operations, values, edges, links = [], [], [], [], []
    block_ids = {b['id']: i for i, b in enumerate(fn['blocks'])}
    names, op_ranges, param_starts = [], [], []
    for bi, block in enumerate(fn['blocks']):
        table = {}
        param_starts.append(len(values))
        for p in block['params']:
            table[p['name']] = len(values)
            values.append((bi, NONE))
        start = len(operations)
        for instruction in block['ops']:
            oi = len(operations)
            arg_start = len(links)
            links.extend(table[name] for name in instruction['args'])
            out_start = len(values)
            for out in instruction['out']:
                table[out['name']] = len(values)
                values.append((bi, oi))
            operations.append((bi, arg_start, len(instruction['args']), out_start, len(instruction['out'])))
        op_ranges.append((start, len(block['ops'])))
        names.append(table)
    for bi, block in enumerate(fn['blocks']):
        term, table = block['term'], names[bi]
        kind = {'ret': 0, 'jump': 1, 'branch': 2, 'trap': 3}[term['op']]
        outgoing = [term] if kind == 1 else [term['then'], term['else']] if kind == 2 else []
        term_values = term['values'] if kind == 0 else ([term['cond']] if kind == 2 else [])
        term_values = [*term_values, *(v for e in outgoing for v in e['args'])]
        ts = len(links)
        links.extend(table[v] for v in term_values)
        blocks.append((param_starts[bi], len(block['params']), *op_ranges[bi],
                       kind, table[term['cond']] if kind == 2 else NONE, ts, len(term_values)))
        for e in outgoing:
            begin = len(links)
            links.extend(table[v] for v in e['args'])
            edges.append((bi, block_ids[e['target']], begin, len(e['args'])))
    source = block_ids[source_block['id']]
    selected = op_ranges[source][0] + selected_index
    header = (MAGIC, len(blocks), len(operations), len(values), len(edges), len(links), source, selected)
    size = 64 + len(blocks)*64 + len(operations)*40 + len(values)*16 + len(edges)*32 + len(links)*8
    if size > MAX_BYTES:
        raise OverflowError('native HIA Agent slice fact packet exceeds 8 MiB profile')
    raw = bytearray(struct.pack('<8Q', *header))
    for rows, width in ((blocks, 8), (operations, 5), (values, 2), (edges, 4)):
        for row in rows: raw.extend(struct.pack('<'+str(width)+'Q', *row))
    if links: raw.extend(struct.pack('<'+str(len(links))+'Q', *links))
    assert len(raw) == size
    return bytes(raw), names, op_ranges


class NativeAgentSlice(NativeHiaJsonImage):
    def run(self, wire: bytes):
        if type(wire) is not bytes or not 64 <= len(wire) <= MAX_BYTES:
            raise ValueError('outside native HIA Agent slice fact profile')
        _, nb, no, nv, _, _, _, _ = struct.unpack_from('<8Q', wire)
        # Header counts must not induce unbounded host allocation. The HIA
        # application still validates every count/range/owner and full length.
        if nb > MAX_BYTES//64 or no > MAX_BYTES//40 or nv > MAX_BYTES//16:
            raise ValueError('invalid native HIA Agent slice counts')
        capacity = 64 + 8*(nb + no + nv)
        scratch = capacity + 8*nb
        source = ctypes.create_string_buffer(wire, len(wire))
        output = ctypes.create_string_buffer(capacity)
        state = ctypes.create_string_buffer(scratch)
        result = self._entry(source, len(wire), output, capacity, state, scratch)
        if result in ERRORS:
            from .hia_program_tools import HIAEditRejected
            raise HIAEditRejected('E_HIA_QUERY: '+ERRORS[result])
        if result != capacity:
            raise ValueError('native HIA Agent slice rejected normalized graph')
        return output.raw


def installed_agent_slice(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentSlice)


def native_edit_slice(native, fn, source_block, selected_index):
    wire, names, ranges = encode_function(fn, source_block, selected_index)
    raw = native.run(wire)
    _, nb, no, nv, _, _, sb, selected = struct.unpack_from('<8Q', wire)
    magic, rb, ro, rv, rs, ri, shown, reserved = struct.unpack_from('<8Q', raw)
    if ((magic, rb, ro, rv, rs, ri, reserved) != (RESULT_MAGIC, nb, no, nv, sb, selected, 0)
            or len(raw) != 64 + 8*(nb + no + nv) or not 1 <= shown <= 256):
        raise ValueError('invalid HIA Agent slice result header')
    flags = struct.unpack_from('<'+str(nb)+'Q', raw, 64)
    flow = struct.unpack_from('<'+str(nv)+'Q', raw, 64+nb*8)
    ops = struct.unpack_from('<'+str(no)+'Q', raw, 64+(nb+nv)*8)
    if (any(x not in (0, 1, 3, 5, 7) for x in flags) or flags[sb] != 0
            or any(x > 3 for x in flow) or any(x > 3 for x in ops)
            or ops[selected] != 3 or sum(x == 3 for x in ops) != 1
            or sum(x != 0 for x in ops) != shown or 1+sum(bool(x) for x in flags) > 64):
        raise ValueError('invalid HIA Agent slice result flags')

    def entries(bi, wanted):
        block = fn['blocks'][bi]
        start, count = ranges[bi]
        return [{'index': i, 'operation': block['ops'][i]}
                for i in range(count) if ops[start+i] == wanted]

    downstream = []
    for bi, block in enumerate(fn['blocks']):
        if not flags[bi]: continue
        downstream.append({'id': block['id'], 'params': block['params'],
            'affected_params': sorted(p['name'] for p in block['params'] if flow[names[bi][p['name']]] & 2),
            'control_reachable': bool(flags[bi] & 2),
            'dependencies': entries(bi, 2), 'consumers': entries(bi, 1),
            'terminator': block['term'], 'branch_condition_affected': bool(flags[bi] & 4)})
    return {x['index'] for x in entries(sb, 2)}, entries(sb, 1), downstream
